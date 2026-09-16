rule TTP_XOR_WriteProcessMemory_cbba {
  strings:
    $key_cbba = { 9c c8 [2] ae ea [2] a8 df [2] 86 df [2] b9 c3 }

  condition:
    any of them
}