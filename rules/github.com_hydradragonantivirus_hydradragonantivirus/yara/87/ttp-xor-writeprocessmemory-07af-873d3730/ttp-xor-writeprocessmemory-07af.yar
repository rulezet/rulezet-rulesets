rule TTP_XOR_WriteProcessMemory_07af {
  strings:
    $key_07af = { 50 dd [2] 62 ff [2] 64 ca [2] 4a ca [2] 75 d6 }

  condition:
    any of them
}