rule TTP_XOR_WriteProcessMemory_cb95 {
  strings:
    $key_cb95 = { 9c e7 [2] ae c5 [2] a8 f0 [2] 86 f0 [2] b9 ec }

  condition:
    any of them
}