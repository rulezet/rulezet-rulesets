rule TTP_XOR_WriteProcessMemory_ddee {
  strings:
    $key_ddee = { 8a 9c [2] b8 be [2] be 8b [2] 90 8b [2] af 97 }

  condition:
    any of them
}