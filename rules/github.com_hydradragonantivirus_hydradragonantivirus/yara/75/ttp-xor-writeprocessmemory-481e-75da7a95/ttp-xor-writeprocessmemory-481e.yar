rule TTP_XOR_WriteProcessMemory_481e {
  strings:
    $key_481e = { 1f 6c [2] 2d 4e [2] 2b 7b [2] 05 7b [2] 3a 67 }

  condition:
    any of them
}