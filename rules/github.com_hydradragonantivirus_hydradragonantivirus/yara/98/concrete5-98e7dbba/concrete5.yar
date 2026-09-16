import "hash"
rule Concrete5 {
  condition:
    
    hash.sha1(0, filesize) == "927bbd60554ae0789d4688738b4ae945195a3c1c" or      hash.sha1(0, filesize) == "67f07022dae5fa39e8a37c09d67cbcb833e10d1f" or      hash.sha1(0, filesize) == "e1dcbc7b05e8ba6cba392f8fd44a3564fcad3666"  }