rule TTP_XOR_WriteProcessMemory_b6fa {
  strings:
    $key_b6fa = { e1 88 [2] d3 aa [2] d5 9f [2] fb 9f [2] c4 83 }

  condition:
    any of them
}