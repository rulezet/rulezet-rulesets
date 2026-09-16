rule TTP_XOR_WriteProcessMemory_51bd {
  strings:
    $key_51bd = { 06 cf [2] 34 ed [2] 32 d8 [2] 1c d8 [2] 23 c4 }

  condition:
    any of them
}