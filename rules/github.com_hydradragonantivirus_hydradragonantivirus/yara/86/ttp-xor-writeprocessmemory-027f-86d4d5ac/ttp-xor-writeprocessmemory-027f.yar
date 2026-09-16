rule TTP_XOR_WriteProcessMemory_027f {
  strings:
    $key_027f = { 55 0d [2] 67 2f [2] 61 1a [2] 4f 1a [2] 70 06 }

  condition:
    any of them
}