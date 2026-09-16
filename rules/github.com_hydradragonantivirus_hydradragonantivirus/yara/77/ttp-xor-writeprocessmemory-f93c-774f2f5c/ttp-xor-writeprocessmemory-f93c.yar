rule TTP_XOR_WriteProcessMemory_f93c {
  strings:
    $key_f93c = { ae 4e [2] 9c 6c [2] 9a 59 [2] b4 59 [2] 8b 45 }

  condition:
    any of them
}