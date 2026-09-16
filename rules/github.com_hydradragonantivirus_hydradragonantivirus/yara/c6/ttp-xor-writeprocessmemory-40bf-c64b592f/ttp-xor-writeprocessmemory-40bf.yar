rule TTP_XOR_WriteProcessMemory_40bf {
  strings:
    $key_40bf = { 17 cd [2] 25 ef [2] 23 da [2] 0d da [2] 32 c6 }

  condition:
    any of them
}