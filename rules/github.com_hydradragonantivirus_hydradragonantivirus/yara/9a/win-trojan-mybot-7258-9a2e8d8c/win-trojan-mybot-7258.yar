rule Win_Trojan_Mybot_7258
{
strings:
	$a0 = { 800d7b336f7d383a94c8ef83f8282ad02baddf0c92247034d0cbe5b185bfc150f0c1e7bcd9d6ae381d1fd32436ffcc2c96dea074f655343773a30764e0b3f4824c4bc61ca653464cebabc37f82c3 }


condition:
	$a0
}