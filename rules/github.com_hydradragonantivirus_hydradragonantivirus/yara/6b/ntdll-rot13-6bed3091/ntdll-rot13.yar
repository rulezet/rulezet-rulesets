rule ntdll_rot13 {
  strings:
    $ntdll_rot13 = "agqyy" nocase ascii wide

  condition:
    all of them
}