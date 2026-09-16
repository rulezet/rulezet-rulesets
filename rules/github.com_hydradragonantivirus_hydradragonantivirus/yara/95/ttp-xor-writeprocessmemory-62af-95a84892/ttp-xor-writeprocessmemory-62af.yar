rule TTP_XOR_WriteProcessMemory_62af {
  strings:
    $key_62af = { 35 dd [2] 07 ff [2] 01 ca [2] 2f ca [2] 10 d6 }

  condition:
    any of them
}