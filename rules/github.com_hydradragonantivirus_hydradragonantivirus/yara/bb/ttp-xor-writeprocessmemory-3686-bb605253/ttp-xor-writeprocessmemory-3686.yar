rule TTP_XOR_WriteProcessMemory_3686 {
  strings:
    $key_3686 = { 61 f4 [2] 53 d6 [2] 55 e3 [2] 7b e3 [2] 44 ff }

  condition:
    any of them
}