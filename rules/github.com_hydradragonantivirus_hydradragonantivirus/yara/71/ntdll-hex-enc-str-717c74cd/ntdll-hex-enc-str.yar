rule ntdll_hex_enc_str {
  strings:
    $ntdll_hex_enc_str = "6e74646c6c" nocase ascii wide

  condition:
    all of them
}