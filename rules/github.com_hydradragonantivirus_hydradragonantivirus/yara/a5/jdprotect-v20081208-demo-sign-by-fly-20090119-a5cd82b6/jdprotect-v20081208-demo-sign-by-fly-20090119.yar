import "pe"
rule JDProtect_V20081208_demo_____________________Sign_By_fly___20090119 {
  strings:
    $a0 = { 10 3C 0C 32 54 50 50 83 2D 51 52 B9 E8 ?? 52 2A 10 16 84 01 }

  condition:
    $a0 at pe.entry_point
}