rule TTP_XOR_WriteProcessMemory_4105 {
  strings:
    $key_4105 = { 16 77 [2] 24 55 [2] 22 60 [2] 0c 60 [2] 33 7c }

  condition:
    any of them
}