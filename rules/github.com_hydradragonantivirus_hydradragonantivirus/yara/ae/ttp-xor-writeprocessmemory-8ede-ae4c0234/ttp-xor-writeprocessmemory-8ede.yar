rule TTP_XOR_WriteProcessMemory_8ede {
  strings:
    $key_8ede = { d9 ac [2] eb 8e [2] ed bb [2] c3 bb [2] fc a7 }

  condition:
    any of them
}