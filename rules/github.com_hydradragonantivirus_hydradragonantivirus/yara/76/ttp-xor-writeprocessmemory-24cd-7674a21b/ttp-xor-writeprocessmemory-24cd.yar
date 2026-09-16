rule TTP_XOR_WriteProcessMemory_24cd {
  strings:
    $key_24cd = { 73 bf [2] 41 9d [2] 47 a8 [2] 69 a8 [2] 56 b4 }

  condition:
    any of them
}