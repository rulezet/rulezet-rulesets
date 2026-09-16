rule TTP_XOR_WriteProcessMemory_27af {
  strings:
    $key_27af = { 70 dd [2] 42 ff [2] 44 ca [2] 6a ca [2] 55 d6 }

  condition:
    any of them
}