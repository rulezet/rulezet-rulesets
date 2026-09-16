rule TTP_XOR_WriteProcessMemory_3194 {
  strings:
    $key_3194 = { 66 e6 [2] 54 c4 [2] 52 f1 [2] 7c f1 [2] 43 ed }

  condition:
    any of them
}