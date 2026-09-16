rule ntdll_hex_movebp {
  strings:
    $ntdll_hex_movebp = { c6 45 ?? 6e c6 45 ?? 74 c6 45 ?? 64 c6 45 ?? 6c c6 45 ?? 6c }

  condition:
    all of them
}