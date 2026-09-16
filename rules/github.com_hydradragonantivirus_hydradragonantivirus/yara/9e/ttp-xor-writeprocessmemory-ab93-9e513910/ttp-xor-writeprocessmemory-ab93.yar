rule TTP_XOR_WriteProcessMemory_ab93 {
  strings:
    $key_ab93 = { fc e1 [2] ce c3 [2] c8 f6 [2] e6 f6 [2] d9 ea }

  condition:
    any of them
}