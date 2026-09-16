rule TTP_XOR_WriteProcessMemory_47af {
  strings:
    $key_47af = { 10 dd [2] 22 ff [2] 24 ca [2] 0a ca [2] 35 d6 }

  condition:
    any of them
}