rule TTP_XOR_WriteProcessMemory_aabf {
  strings:
    $key_aabf = { fd cd [2] cf ef [2] c9 da [2] e7 da [2] d8 c6 }

  condition:
    any of them
}