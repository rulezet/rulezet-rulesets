rule TTP_XOR_WriteProcessMemory_dffd {
  strings:
    $key_dffd = { 88 8f [2] ba ad [2] bc 98 [2] 92 98 [2] ad 84 }

  condition:
    any of them
}