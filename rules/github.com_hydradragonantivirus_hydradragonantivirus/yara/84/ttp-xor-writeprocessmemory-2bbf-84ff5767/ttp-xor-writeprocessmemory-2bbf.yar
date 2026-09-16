rule TTP_XOR_WriteProcessMemory_2bbf {
  strings:
    $key_2bbf = { 7c cd [2] 4e ef [2] 48 da [2] 66 da [2] 59 c6 }

  condition:
    any of them
}