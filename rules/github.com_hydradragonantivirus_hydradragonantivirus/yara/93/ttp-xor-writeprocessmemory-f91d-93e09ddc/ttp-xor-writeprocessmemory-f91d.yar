rule TTP_XOR_WriteProcessMemory_f91d {
  strings:
    $key_f91d = { ae 6f [2] 9c 4d [2] 9a 78 [2] b4 78 [2] 8b 64 }

  condition:
    any of them
}