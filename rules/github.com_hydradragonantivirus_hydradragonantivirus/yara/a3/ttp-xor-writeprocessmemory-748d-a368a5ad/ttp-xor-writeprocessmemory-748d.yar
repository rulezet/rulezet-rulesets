rule TTP_XOR_WriteProcessMemory_748d {
  strings:
    $key_748d = { 23 ff [2] 11 dd [2] 17 e8 [2] 39 e8 [2] 06 f4 }

  condition:
    any of them
}