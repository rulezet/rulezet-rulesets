rule TTP_XOR_WriteProcessMemory_d9af {
  strings:
    $key_d9af = { 8e dd [2] bc ff [2] ba ca [2] 94 ca [2] ab d6 }

  condition:
    any of them
}