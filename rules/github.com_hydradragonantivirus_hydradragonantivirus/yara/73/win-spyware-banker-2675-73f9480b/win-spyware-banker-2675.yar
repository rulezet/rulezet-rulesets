rule Win_Spyware_Banker_2675
{
strings:
	$a0 = { 03803d46d62aa9a0a7b06fcd565680da6243f4ed928cce6c1c8efe5ea6e1b9673ed55fb2d6beab110dc35f43a5571cffe3290e9c38f4afae0103c38c9c91ae02e502dba679ece5712bf6f545f05c }


condition:
	$a0
}