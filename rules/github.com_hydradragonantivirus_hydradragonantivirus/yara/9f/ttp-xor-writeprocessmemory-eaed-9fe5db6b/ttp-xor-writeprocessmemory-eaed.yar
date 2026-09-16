rule TTP_XOR_WriteProcessMemory_eaed {
  strings:
    $key_eaed = { bd 9f [2] 8f bd [2] 89 88 [2] a7 88 [2] 98 94 }

  condition:
    any of them
}