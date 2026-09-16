rule TTP_XOR_WriteProcessMemory_314a {
  strings:
    $key_314a = { 66 38 [2] 54 1a [2] 52 2f [2] 7c 2f [2] 43 33 }

  condition:
    any of them
}