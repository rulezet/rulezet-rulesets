rule ntdll_flipflop {
  strings:
    $ntdll_flipflop = "tnldl" nocase ascii wide

  condition:
    all of them
}