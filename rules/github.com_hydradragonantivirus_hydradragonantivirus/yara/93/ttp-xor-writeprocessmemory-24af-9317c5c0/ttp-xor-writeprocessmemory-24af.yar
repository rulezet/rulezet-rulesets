rule TTP_XOR_WriteProcessMemory_24af {
  strings:
    $key_24af = { 73 dd [2] 41 ff [2] 47 ca [2] 69 ca [2] 56 d6 }

  condition:
    any of them
}