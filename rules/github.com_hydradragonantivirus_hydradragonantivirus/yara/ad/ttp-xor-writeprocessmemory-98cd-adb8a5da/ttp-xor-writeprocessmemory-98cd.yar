rule TTP_XOR_WriteProcessMemory_98cd {
  strings:
    $key_98cd = { cf bf [2] fd 9d [2] fb a8 [2] d5 a8 [2] ea b4 }

  condition:
    any of them
}