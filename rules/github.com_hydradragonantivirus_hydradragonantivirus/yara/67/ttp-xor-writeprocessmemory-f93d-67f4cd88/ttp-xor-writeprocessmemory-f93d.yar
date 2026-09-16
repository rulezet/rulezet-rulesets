rule TTP_XOR_WriteProcessMemory_f93d {
  strings:
    $key_f93d = { ae 4f [2] 9c 6d [2] 9a 58 [2] b4 58 [2] 8b 44 }

  condition:
    any of them
}