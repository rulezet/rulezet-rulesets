rule TTP_XOR_WriteProcessMemory_1fd3 {
  strings:
    $key_1fd3 = { 48 a1 [2] 7a 83 [2] 7c b6 [2] 52 b6 [2] 6d aa }

  condition:
    any of them
}