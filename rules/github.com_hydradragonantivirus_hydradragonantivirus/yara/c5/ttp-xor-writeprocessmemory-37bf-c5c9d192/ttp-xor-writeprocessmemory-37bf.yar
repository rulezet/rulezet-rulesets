rule TTP_XOR_WriteProcessMemory_37bf {
  strings:
    $key_37bf = { 60 cd [2] 52 ef [2] 54 da [2] 7a da [2] 45 c6 }

  condition:
    any of them
}