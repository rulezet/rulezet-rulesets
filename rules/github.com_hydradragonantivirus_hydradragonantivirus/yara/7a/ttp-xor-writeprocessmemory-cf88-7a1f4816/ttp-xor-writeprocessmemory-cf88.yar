rule TTP_XOR_WriteProcessMemory_cf88 {
  strings:
    $key_cf88 = { 98 fa [2] aa d8 [2] ac ed [2] 82 ed [2] bd f1 }

  condition:
    any of them
}