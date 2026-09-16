rule TTP_XOR_WriteProcessMemory_febf {
  strings:
    $key_febf = { a9 cd [2] 9b ef [2] 9d da [2] b3 da [2] 8c c6 }

  condition:
    any of them
}