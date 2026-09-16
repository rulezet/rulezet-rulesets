rule TTP_XOR_WriteProcessMemory_ddb8 {
  strings:
    $key_ddb8 = { 8a ca [2] b8 e8 [2] be dd [2] 90 dd [2] af c1 }

  condition:
    any of them
}