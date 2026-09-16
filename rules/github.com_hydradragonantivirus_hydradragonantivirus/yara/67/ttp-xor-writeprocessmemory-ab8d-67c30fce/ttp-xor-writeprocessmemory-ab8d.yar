rule TTP_XOR_WriteProcessMemory_ab8d {
  strings:
    $key_ab8d = { fc ff [2] ce dd [2] c8 e8 [2] e6 e8 [2] d9 f4 }

  condition:
    any of them
}