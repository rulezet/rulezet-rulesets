rule TTP_XOR_WriteProcessMemory_89b6 {
  strings:
    $key_89b6 = { de c4 [2] ec e6 [2] ea d3 [2] c4 d3 [2] fb cf }

  condition:
    any of them
}