rule TTP_XOR_WriteProcessMemory_f4cd {
  strings:
    $key_f4cd = { a3 bf [2] 91 9d [2] 97 a8 [2] b9 a8 [2] 86 b4 }

  condition:
    any of them
}