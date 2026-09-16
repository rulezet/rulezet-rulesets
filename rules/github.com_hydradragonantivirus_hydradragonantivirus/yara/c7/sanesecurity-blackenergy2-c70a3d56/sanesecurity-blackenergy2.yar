rule Sanesecurity_BlackEnergy2 {
  strings:
    $ex1 = "DispatchCommand" ascii
    $ex2 = "DispatchEvent" ascii
    $a1  = { 68 A1 B0 5C 72 }
    $a2  = "hkCYN"
    $a3  = { 68 E6 4B 59 4E }

  condition:
    all of ($ex*) and 3 of ($a*)
}