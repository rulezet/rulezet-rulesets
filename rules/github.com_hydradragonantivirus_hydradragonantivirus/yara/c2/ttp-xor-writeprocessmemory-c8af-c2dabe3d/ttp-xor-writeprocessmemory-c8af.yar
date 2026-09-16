rule TTP_XOR_WriteProcessMemory_c8af {
  strings:
    $key_c8af = { 9f dd [2] ad ff [2] ab ca [2] 85 ca [2] ba d6 }

  condition:
    any of them
}