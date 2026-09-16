rule TTP_XOR_WriteProcessMemory_fcee {
  strings:
    $key_fcee = { ab 9c [2] 99 be [2] 9f 8b [2] b1 8b [2] 8e 97 }

  condition:
    any of them
}