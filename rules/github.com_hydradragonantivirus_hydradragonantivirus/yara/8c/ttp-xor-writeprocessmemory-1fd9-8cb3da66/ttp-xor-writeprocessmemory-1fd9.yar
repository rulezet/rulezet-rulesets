rule TTP_XOR_WriteProcessMemory_1fd9 {
  strings:
    $key_1fd9 = { 48 ab [2] 7a 89 [2] 7c bc [2] 52 bc [2] 6d a0 }

  condition:
    any of them
}