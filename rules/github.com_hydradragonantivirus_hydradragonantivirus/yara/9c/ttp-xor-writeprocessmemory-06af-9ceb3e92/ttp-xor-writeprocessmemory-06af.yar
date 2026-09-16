rule TTP_XOR_WriteProcessMemory_06af {
  strings:
    $key_06af = { 51 dd [2] 63 ff [2] 65 ca [2] 4b ca [2] 74 d6 }

  condition:
    any of them
}