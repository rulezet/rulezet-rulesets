rule TTP_XOR_WriteProcessMemory_e335 {
  strings:
    $key_e335 = { b4 47 [2] 86 65 [2] 80 50 [2] ae 50 [2] 91 4c }

  condition:
    any of them
}