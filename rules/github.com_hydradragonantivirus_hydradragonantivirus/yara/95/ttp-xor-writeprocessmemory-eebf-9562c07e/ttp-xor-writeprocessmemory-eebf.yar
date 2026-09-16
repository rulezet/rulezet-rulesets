rule TTP_XOR_WriteProcessMemory_eebf {
  strings:
    $key_eebf = { b9 cd [2] 8b ef [2] 8d da [2] a3 da [2] 9c c6 }

  condition:
    any of them
}