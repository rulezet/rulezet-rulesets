rule TTP_XOR_WriteProcessMemory_fdea {
  strings:
    $key_fdea = { aa 98 [2] 98 ba [2] 9e 8f [2] b0 8f [2] 8f 93 }

  condition:
    any of them
}